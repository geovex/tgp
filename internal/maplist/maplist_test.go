package maplist

import (
	"slices"
	"testing"
)

func TestMapList(t *testing.T) {
	mapList := New[int, int]()
	mapList.Add(1, 1)
	mapList.Add(1, 2)
	mapList.Add(3, 3)
	mapList.Add(4, 4)
	test_list := []int{1, 2}
	if !slices.Equal(mapList.Data[1], test_list) {
		t.Errorf("Expected %v, got %v", []int{1, 2}, mapList.Data[1])
	}
	for i := 0; i < 10; i++ {
		varndValue, ok := mapList.GetRandom(1)
		if !ok || slices.Index(test_list, varndValue) == -1 {
			t.Errorf("Expected true, got false")
		}
	}
	rndValue, ok := mapList.GetRandom(3)
	if !ok || rndValue != 3 {
		t.Errorf("Expected %v, got %v", 3, rndValue)
	}
	rndValue, ok = mapList.GetRandom(4)
	if !ok || rndValue != 4 {
		t.Errorf("Expected %v, got %v", 4, rndValue)
	}
	rndValue, ok = mapList.GetRandom(5)
	if ok {
		t.Errorf("Expected false, got %v", rndValue)
	}
}
